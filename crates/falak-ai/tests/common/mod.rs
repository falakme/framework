//! A Notebook app on SQLite with the test authenticator, shared by the tests.
#![allow(dead_code)]

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use falak_contracts::{identity::RequestContext, ir::Ir};
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

pub const ALICE: &str = "aaaaaaaa-0000-4000-8000-000000000001";
pub const BOB: &str = "bbbbbbbb-0000-4000-8000-000000000002";

pub fn ir() -> Ir {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let (project, diags) = load_project(&[
        f(
            "app.yaml",
            include_str!("../../../../examples/notebook/app.yaml"),
        ),
        f(
            "entities/note.yaml",
            include_str!("../../../../examples/notebook/entities/note.yaml"),
        ),
        f(
            "entities/notebook.yaml",
            include_str!("../../../../examples/notebook/entities/notebook.yaml"),
        ),
        f(
            "policies/note.yaml",
            include_str!("../../../../examples/notebook/policies/note.yaml"),
        ),
        f(
            "policies/notebook.yaml",
            include_str!("../../../../examples/notebook/policies/notebook.yaml"),
        ),
        f(
            "commands/archive_note.yaml",
            include_str!("../../../../examples/notebook/commands/archive_note.yaml"),
        ),
        f(
            "commands/restore_note.yaml",
            include_str!("../../../../examples/notebook/commands/restore_note.yaml"),
        ),
    ]);
    assert!(diags.is_empty(), "{diags:?}");
    build_ir(&project.unwrap())
}

pub struct World {
    pub ir: Arc<Ir>,
    pub app: Router,
}

/// ClarityAI: its `document.body` is marked `pii: true`.
pub fn clarity_ir() -> Ir {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let (project, diags) = load_project(&[
        f(
            "app.yaml",
            include_str!("../../../../testdata/apps/clarityai/app.yaml"),
        ),
        f(
            "entities/document.yaml",
            include_str!("../../../../testdata/apps/clarityai/entities/document.yaml"),
        ),
        f(
            "entities/summary.yaml",
            include_str!("../../../../testdata/apps/clarityai/entities/summary.yaml"),
        ),
        f(
            "policies/document.yaml",
            include_str!("../../../../testdata/apps/clarityai/policies/document.yaml"),
        ),
        f(
            "policies/summary.yaml",
            include_str!("../../../../testdata/apps/clarityai/policies/summary.yaml"),
        ),
    ]);
    assert!(diags.is_empty(), "{diags:?}");
    build_ir(&project.unwrap())
}

pub async fn world() -> World {
    world_with(ir()).await
}

pub async fn world_with(ir: Ir) -> World {
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    let ir = Arc::new(ir);
    let ctx = RequestContext {
        principal: None,
        request_id: "setup".into(),
    };
    assert!(apply_initial_migration(&*driver, &ctx, &ir).await.unwrap());
    let app = create_router(ir.clone(), driver, Arc::new(DevAuthenticator));
    World { ir, app }
}

pub async fn rest(
    app: &Router,
    who: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {who}"));
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let res = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Alice and Bob each have a notebook and a note.
pub async fn seed(app: &Router) -> (String, String) {
    let mut ids = Vec::new();
    for (who, title) in [(ALICE, "alice's secret plan"), (BOB, "bob's shopping")] {
        let (s, nb) = rest(
            app,
            who,
            "POST",
            "/v1/notebooks",
            Some(json!({"title": "book"})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{nb}");
        let nb_id = nb["id"].as_str().unwrap().to_owned();
        let (s, n) = rest(
            app,
            who,
            "POST",
            "/v1/notes",
            Some(json!({"title": title, "notebook_id": nb_id})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{n}");
        ids.push(n["id"].as_str().unwrap().to_owned());
    }
    (ids[0].clone(), ids[1].clone())
}

/// One JSON-RPC call to `/mcp`.
pub async fn rpc(
    app: &Router,
    who: Option<&str>,
    method: &str,
    params: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    if let Some(w) = who {
        req = req.header("authorization", format!("Bearer {w}"));
    }
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub async fn call_tool(app: &Router, who: &str, name: &str, args: Value) -> (StatusCode, Value) {
    rpc(
        app,
        Some(who),
        "tools/call",
        json!({"name": name, "arguments": args}),
    )
    .await
}
