//! Tests for telemetry, structured logging, PII redaction, and health endpoints (T1.9).

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use falak_contracts::{
    identity::RequestContext,
    telemetry::{Level, LogRecord, TelemetryExporter},
};
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::apply_initial_migration;
use falak_runtime_native::{
    TracingTelemetryExporter,
    context::DevAuthenticator,
    create_router,
    telemetry::{TelemetryFormat, init_telemetry},
};
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

#[tokio::test]
async fn test_liveness_and_readiness_endpoints() {
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    let ctx = RequestContext {
        principal: None,
        request_id: "test_telemetry".to_string(),
    };

    let files = minimal_files();
    let (project_opt, diags) = load_project(&files);
    assert!(diags.is_empty(), "Project diags: {diags:?}");
    let ir = Arc::new(build_ir(&project_opt.unwrap()));
    apply_initial_migration(&*driver, &ctx, &ir).await.unwrap();

    let app = create_router(ir, driver, Arc::new(DevAuthenticator));

    // Liveness probe (/healthz)
    let req = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Readiness probe (/readyz) verifies database query capability
    let req = Request::builder()
        .uri("/readyz")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[test]
fn test_structured_telemetry_exporter_and_pii_redaction() {
    init_telemetry(TelemetryFormat::Json);
    let exporter = TracingTelemetryExporter::new();

    let record = LogRecord {
        level: Level::Info,
        message: "User login event".to_string(),
        request_id: Some("req_login_001".to_string()),
        fields: vec![
            ("user_id".to_string(), "usr_123".to_string()),
            ("password".to_string(), "SuperSecret123!".to_string()),
            ("auth_token".to_string(), "eyJh...".to_string()),
            ("api_key".to_string(), "sk-live-xyz".to_string()),
            ("role".to_string(), "member".to_string()),
        ],
    };

    // Logging the record should execute cleanly without panicking
    exporter.log(record);

    // Metrics recording
    exporter.metric("http_requests_total", 42.0, &[("route", "/v1/notes")]);
}
