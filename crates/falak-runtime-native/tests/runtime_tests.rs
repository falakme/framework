//! Comprehensive integration tests for Native Runtime (T1.7).

use std::sync::Arc;

use axum::{
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
use falak_runtime_native::create_router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;
use unicode_normalization::UnicodeNormalization;

fn dummy_context() -> RequestContext {
    RequestContext {
        principal: None,
        request_id: "test_migrate_req".to_string(),
    }
}

fn minimal_files() -> Vec<SourceFile> {
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

async fn setup_app() -> (axum::Router, Arc<SqliteDriver>) {
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    let ctx = dummy_context();

    let files = minimal_files();
    let (project_opt, diags) = load_project(&files);
    assert!(diags.is_empty(), "Project diags: {diags:?}");
    let project = project_opt.unwrap();
    let ir = Arc::new(build_ir(&project));

    let applied = apply_initial_migration(&*driver, &ctx, &ir).await.unwrap();
    assert!(applied, "Migration applied");

    let app = create_router(ir, driver.clone());
    (app, driver)
}

async fn response_json(res: axum::response::Response) -> (StatusCode, Value) {
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn test_health_and_ready_and_not_found() {
    let (app, _) = setup_app().await;

    // GET /healthz
    let req = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes.as_ref(), b"ok");

    // GET /readyz
    let req = Request::builder()
        .uri("/readyz")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes.as_ref(), b"ok");

    // Unknown endpoint -> 404 Problem Details
    let req = Request::builder()
        .uri("/v1/unknown")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("application/problem+json")
    );
    let (_, json) = response_json(res).await;
    assert_eq!(json["code"], "not_found");
    assert_eq!(json["instance"], "/v1/unknown");
}

#[tokio::test]
async fn test_rest_crud_and_commands_lifecycle_with_isolation() {
    let (app, _) = setup_app().await;

    let user1 = "00000000-0000-0000-0000-000000000001";
    let user2 = "00000000-0000-0000-0000-000000000002";

    // 1. Unauthenticated creation -> 403 Forbidden
    let req = Request::builder()
        .method("POST")
        .uri("/v1/notes")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"title":"Unauthorized"}"#))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let (_, json) = response_json(res).await;
    assert_eq!(json["code"], "forbidden");

    // 2. User 1 creates Note 1 with Idempotency-Key
    let req = Request::builder()
        .method("POST")
        .uri("/v1/notes")
        .header("authorization", format!("Bearer {user1}"))
        .header("idempotency-key", "key-first-note")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"title":"Note 1","body":"Hello Dev2"}"#))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(res.headers().get(header::ETAG).unwrap(), "W/\"1\"");
    let loc = res
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(loc.starts_with("/v1/notes/"));
    let (_, created_json) = response_json(res).await;
    let note_id = created_json["id"].as_str().unwrap().to_string();
    assert_eq!(created_json["title"], "Note 1");
    assert_eq!(created_json["body"], "Hello Dev2");
    assert_eq!(created_json["version"], 1);
    assert_eq!(created_json["archived"], false);

    // 3. Idempotent replay: exact same key & body -> 201 Created with idempotent-replayed: true
    let req = Request::builder()
        .method("POST")
        .uri("/v1/notes")
        .header("authorization", format!("Bearer {user1}"))
        .header("idempotency-key", "key-first-note")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"title":"Note 1","body":"Hello Dev2"}"#))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(res.headers().get("idempotent-replayed").unwrap(), "true");
    let (_, replay_json) = response_json(res).await;
    assert_eq!(replay_json["id"], note_id);

    // 4. Same idempotency key with different payload -> 400 Bad Request
    let req = Request::builder()
        .method("POST")
        .uri("/v1/notes")
        .header("authorization", format!("Bearer {user1}"))
        .header("idempotency-key", "key-first-note")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"title":"Different Payload"}"#))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let (_, err_json) = response_json(res).await;
    assert_eq!(err_json["code"], "idempotency_payload_mismatch");

    // 5. User 1 GET /v1/notes/{id} -> 200 OK
    let req = Request::builder()
        .uri(format!("/v1/notes/{note_id}"))
        .header("authorization", format!("Bearer {user1}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(header::ETAG).unwrap(), "W/\"1\"");
    let (_, get_json) = response_json(res).await;
    assert_eq!(get_json["id"], note_id);
    assert_eq!(get_json["title"], "Note 1");

    // 6. User 2 GET /v1/notes/{id} -> 404 Not Found (User isolation check!)
    let req = Request::builder()
        .uri(format!("/v1/notes/{note_id}"))
        .header("authorization", format!("Bearer {user2}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // 7. User 1 lists notes -> 1 note
    let req = Request::builder()
        .uri("/v1/notes")
        .header("authorization", format!("Bearer {user1}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let (_, list_json) = response_json(res).await;
    assert_eq!(list_json["data"].as_array().unwrap().len(), 1);

    // 8. User 2 lists notes -> empty list
    let req = Request::builder()
        .uri("/v1/notes")
        .header("authorization", format!("Bearer {user2}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let (_, list_json) = response_json(res).await;
    assert_eq!(list_json["data"].as_array().unwrap().len(), 0);

    // 9. User 1 PATCH /v1/notes/{id} with stale If-Match -> 412 Precondition Failed
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/notes/{note_id}"))
        .header("authorization", format!("Bearer {user1}"))
        .header("if-match", "W/\"99\"")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"title":"Stale Update"}"#))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
    let (_, err_json) = response_json(res).await;
    assert_eq!(err_json["code"], "precondition_failed");

    // 10. User 1 PATCH /v1/notes/{id} with valid If-Match -> 200 OK, bumped version 2
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/notes/{note_id}"))
        .header("authorization", format!("Bearer {user1}"))
        .header("if-match", "W/\"1\"")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"title":"Updated Title"}"#))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(header::ETAG).unwrap(), "W/\"2\"");
    let (_, update_json) = response_json(res).await;
    assert_eq!(update_json["title"], "Updated Title");
    assert_eq!(update_json["version"], 2);

    // 11. Command execution: archive note -> 200 OK, version bumped to 3, archived true
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/notes/{note_id}/archive_note"))
        .header("authorization", format!("Bearer {user1}"))
        .header("if-match", "W/\"2\"")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(header::ETAG).unwrap(), "W/\"3\"");
    let (_, cmd_json) = response_json(res).await;
    assert_eq!(cmd_json["archived"], true);
    assert_eq!(cmd_json["version"], 3);

    // 12. User 2 attempts to delete User 1's note -> 404 Not Found
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/notes/{note_id}"))
        .header("authorization", format!("Bearer {user2}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // 13. User 1 deletes Note -> 204 No Content
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/notes/{note_id}"))
        .header("authorization", format!("Bearer {user1}"))
        .header("if-match", "W/\"3\"")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // 14. GET deleted note -> 404 Not Found (soft-deleted row filtered out)
    let req = Request::builder()
        .uri(format!("/v1/notes/{note_id}"))
        .header("authorization", format!("Bearer {user1}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_keyset_pagination_sorting_and_filtering() {
    let (app, _) = setup_app().await;
    let user = "00000000-0000-0000-0000-000000000001";

    // Seed 5 notes with distinct titles
    let titles = ["Alpha", "Beta", "Gamma", "Delta", "Epsilon"];
    for title in titles {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/notes")
            .header("authorization", format!("Bearer {user}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(r#"{{"title":"{title}"}}"#)))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
    }

    // Page 1: page_size=2, sort=title (ascending)
    let req = Request::builder()
        .uri("/v1/notes?page[size]=2&sort=title")
        .header("authorization", format!("Bearer {user}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let (_, p1_json) = response_json(res).await;
    let data = p1_json["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(data[0]["title"], "Alpha");
    assert_eq!(data[1]["title"], "Beta");
    assert_eq!(p1_json["meta"]["has_more"], true);
    let cursor1 = p1_json["meta"]["next_cursor"].as_str().unwrap().to_string();

    // Page 2: using cursor
    let req = Request::builder()
        .uri(format!(
            "/v1/notes?page[size]=2&sort=title&page[after]={cursor1}"
        ))
        .header("authorization", format!("Bearer {user}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let (_, p2_json) = response_json(res).await;
    let data = p2_json["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(data[0]["title"], "Delta");
    assert_eq!(data[1]["title"], "Epsilon");
    assert_eq!(p2_json["meta"]["has_more"], true);
    let cursor2 = p2_json["meta"]["next_cursor"].as_str().unwrap().to_string();

    // Page 3: last note
    let req = Request::builder()
        .uri(format!(
            "/v1/notes?page[size]=2&sort=title&page[after]={cursor2}"
        ))
        .header("authorization", format!("Bearer {user}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let (_, p3_json) = response_json(res).await;
    let data = p3_json["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["title"], "Gamma");
    assert_eq!(p3_json["meta"]["has_more"], false);
    assert!(p3_json["meta"]["next_cursor"].is_null());

    // Filtering by title: filter[title]=Beta
    let req = Request::builder()
        .uri("/v1/notes?filter[title]=Beta")
        .header("authorization", format!("Bearer {user}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let (_, filter_json) = response_json(res).await;
    let filtered_data = filter_json["data"].as_array().unwrap();
    assert_eq!(filtered_data.len(), 1);
    assert_eq!(filtered_data[0]["title"], "Beta");
}

#[tokio::test]
async fn test_unicode_nfc_normalization() {
    let (app, _) = setup_app().await;
    let user = "00000000-0000-0000-0000-000000000001";

    // "Café" with 'e' + combining acute accent (decomposed NFD)
    let nfd_title = "Cafe\u{0301}";
    let nfc_expected = "Café";
    assert_ne!(nfd_title, nfc_expected);
    assert_eq!(nfd_title.nfc().collect::<String>(), nfc_expected);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/notes")
        .header("authorization", format!("Bearer {user}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"title":"{nfd_title}"}}"#)))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let (_, json) = response_json(res).await;
    assert_eq!(json["title"], nfc_expected);

    // Query filter with decomposed NFD string -> matches composed NFC in database
    let req = Request::builder()
        .uri(format!("/v1/notes?filter[title]={nfd_title}"))
        .header("authorization", format!("Bearer {user}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let (_, filter_json) = response_json(res).await;
    let data = filter_json["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["title"], nfc_expected);
}
