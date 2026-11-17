use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use falak_contracts::{
    driver::{Statement, StorageDriver},
    identity::{Principal, RequestContext},
};
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_postgres::{PostgresConfig, PostgresDriver};
use falak_migrate::apply_initial_migration;
use falak_runtime_native::{context::DevAuthenticator, create_router};
use serde_json::{Value, json};
use tower::ServiceExt;

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

fn get_test_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:54321/falak_test".to_string())
}

async fn setup_postgres_driver() -> Option<PostgresDriver> {
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
            eprintln!("Skipping PostgreSQL runtime test: {e}");
            None
        }
    }
}

#[tokio::test]
async fn test_postgres_runtime_rest_crud_and_isolation() {
    let Some(driver) = setup_postgres_driver().await else {
        return;
    };

    let ctx = RequestContext {
        principal: Some(Principal {
            subject: "user_pg_admin".to_string(),
            tenant: None,
            roles: vec!["admin".to_string()],
        }),
        request_id: "req_pg_init".to_string(),
    };

    // Clean any prior tables
    let _ = driver
        .batch(
            &ctx,
            vec![
                Statement::new("DROP TABLE IF EXISTS \"notes\";", vec![]),
                Statement::new("DROP TABLE IF EXISTS \"notebooks\";", vec![]),
                Statement::new("DROP TABLE IF EXISTS \"_falak_migrations\";", vec![]),
                Statement::new("DROP TABLE IF EXISTS \"_falak_schema\";", vec![]),
            ],
        )
        .await;

    // Build the minimal app IR
    let (project_opt, diags) = load_project(&minimal_files());
    assert!(diags.is_empty(), "Project diags: {diags:?}");
    let project = project_opt.unwrap();
    let ir_arc = Arc::new(build_ir(&project));

    // Apply migrations to PostgreSQL
    let applied = apply_initial_migration(&driver, &ctx, &ir_arc)
        .await
        .expect("migration failed on postgres");
    assert!(applied, "Initial migration should have applied");

    // Second run should report already up to date
    let second_applied = apply_initial_migration(&driver, &ctx, &ir_arc)
        .await
        .expect("second migration failed");
    assert!(!second_applied, "Second migration should be up-to-date");

    // Setup native Axum router on top of PostgresDriver
    let auth = Arc::new(DevAuthenticator);
    let app = create_router(ir_arc.clone(), Arc::new(driver.clone()), auth);

    // 1. Health check & Ready check (with database ping)
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let user_a = "00000000-0000-0000-0000-00000000000a";
    let user_b = "00000000-0000-0000-0000-00000000000b";

    // 2. User A creates a note in PostgreSQL
    let create_payload = json!({
        "title": "Postgres Note",
        "body": "Running on PostgreSQL!",
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/notes")
        .header("authorization", format!("Bearer {user_a}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let etag = res
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let created_json: Value = serde_json::from_slice(&bytes).unwrap();
    let note_id = created_json["id"].as_str().unwrap().to_string();
    assert_eq!(created_json["title"], "Postgres Note");

    // 3. User A can GET their note
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/notes/{note_id}"))
        .header("authorization", format!("Bearer {user_a}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 4. User B gets 404 NOT FOUND for User A's note (Multi-User Isolation)
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/notes/{note_id}"))
        .header("authorization", format!("Bearer {user_b}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // 5. User A updates their note with If-Match
    let update_payload = json!({
        "title": "Postgres Note Updated",
    });
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/notes/{note_id}"))
        .header("authorization", format!("Bearer {user_a}"))
        .header("if-match", etag)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&update_payload).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let updated_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(updated_json["title"], "Postgres Note Updated");

    // 6. User A lists notes: sees 1 note
    let req = Request::builder()
        .method("GET")
        .uri("/v1/notes")
        .header("authorization", format!("Bearer {user_a}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let list_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(list_json["data"].as_array().unwrap().len(), 1);

    // 7. User B lists notes: sees 0 notes
    let req = Request::builder()
        .method("GET")
        .uri("/v1/notes")
        .header("authorization", format!("Bearer {user_b}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 64)
        .await
        .unwrap();
    let list_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(list_json["data"].as_array().unwrap().len(), 0);

    // 8. User A deletes the note
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/notes/{note_id}"))
        .header("authorization", format!("Bearer {user_a}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // Clean up tables
    let _ = driver
        .batch(
            &ctx,
            vec![
                Statement::new("DROP TABLE IF EXISTS \"notes\";", vec![]),
                Statement::new("DROP TABLE IF EXISTS \"notebooks\";", vec![]),
                Statement::new("DROP TABLE IF EXISTS \"_falak_migrations\";", vec![]),
            ],
        )
        .await;
}
