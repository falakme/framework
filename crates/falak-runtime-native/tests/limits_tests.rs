//! Request limits on the data routes (T2.10): rate, body size, and the auth routes'
//! public key set (T2.9).

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use falak_auth::ratelimit::Rate;
use falak_contracts::identity::RequestContext;
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::apply_initial_migration;
use falak_runtime_native::{
    RouterOptions,
    context::DevAuthenticator,
    create_router_with,
    limits::{Limits, MemoryGate},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

fn files() -> Vec<SourceFile> {
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

async fn app(limits: Limits) -> axum::Router {
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    let (project, diags) = load_project(&files());
    assert!(diags.is_empty(), "{diags:?}");
    let ir = Arc::new(build_ir(&project.unwrap()));
    let ctx = RequestContext {
        principal: None,
        request_id: "limits".into(),
    };
    apply_initial_migration(&*driver, &ctx, &ir).await.unwrap();
    create_router_with(
        ir,
        driver,
        Arc::new(DevAuthenticator),
        RouterOptions {
            limits,
            ..RouterOptions::default()
        },
    )
}

fn limits(limit: u32) -> Limits {
    Limits {
        rate: Some(Arc::new(MemoryGate::new(Rate {
            limit,
            window_secs: 60,
        }))),
        max_body_bytes: 256,
        timeout: Some(Duration::from_secs(5)),
    }
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(
            "authorization",
            "Bearer 00000000-0000-0000-0000-000000000001",
        )
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn requests_over_the_rate_are_refused_with_429_and_headers() {
    let app = app(limits(3)).await;
    for _ in 0..3 {
        let res = app.clone().oneshot(get("/v1/notes")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers().contains_key("ratelimit-remaining"));
    }
    let res = app.clone().oneshot(get("/v1/notes")).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key("retry-after"));
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "rate_limited");
}

#[tokio::test]
async fn health_probes_are_not_limited() {
    let app = app(limits(1)).await;
    assert_eq!(
        app.clone()
            .oneshot(get("/v1/notes"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    for _ in 0..5 {
        let res = app.clone().oneshot(get("/healthz")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn a_body_over_the_limit_is_413() {
    let app = app(limits(100)).await;
    let big = format!(r#"{{"title":"{}"}}"#, "x".repeat(1000));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/notes")
        .header(
            "authorization",
            "Bearer 00000000-0000-0000-0000-000000000001",
        )
        .header("content-type", "application/json")
        .body(Body::from(big))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "payload_too_large");
}

#[tokio::test]
async fn a_slow_request_ends_with_a_504_problem() {
    use axum::{Router, middleware::from_fn_with_state, routing::get as route_get};
    let app = Router::new()
        .route(
            "/slow",
            route_get(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                "late"
            }),
        )
        .layer(from_fn_with_state(
            Duration::from_millis(50),
            falak_runtime_native::limits::time_limit,
        ));
    let res = app.oneshot(get("/slow")).await.unwrap();
    assert_eq!(res.status(), StatusCode::GATEWAY_TIMEOUT);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "execution_timeout");
}

#[tokio::test]
async fn a_small_body_still_works() {
    let app = app(limits(100)).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/notes")
        .header(
            "authorization",
            "Bearer 00000000-0000-0000-0000-000000000001",
        )
        .header("content-type", "application/json")
        .body(Body::from(r#"{"title":"hi","body":"there"}"#))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn the_limit_can_be_turned_off() {
    let app = app(Limits {
        rate: None,
        ..limits(1)
    })
    .await;
    for _ in 0..10 {
        let res = app.clone().oneshot(get("/v1/notes")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
