//! `/v1/_files`: upload, check, publish and download, and who may touch whose file (T3.11).

use std::{future::Future, pin::Pin, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use falak_contracts::{Error, Result, identity::Principal};
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::{MigrateOptions, migrate};
use falak_runtime_native::{
    RouterOptions,
    context::{Authenticator, bearer_token},
    create_router_with,
    files::{FileApi, UploadTicket},
};
use falak_storage::{FileFlow, MemoryBackend, S3Config, UploadLimits};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const T1: &str = "00000000-0000-0000-0000-0000000000a1";
const T2: &str = "00000000-0000-0000-0000-0000000000a2";
const ALICE: &str = "00000000-0000-0000-0000-00000000000a";
const BOB: &str = "00000000-0000-0000-0000-00000000000b";
const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4];

/// Test only: `Bearer <subject>@<tenant>`.
struct TenantAuth;
impl Authenticator for TenantAuth {
    fn authenticate(&self, headers: &HeaderMap) -> Option<Principal> {
        let (subject, tenant) = bearer_token(headers)?.split_once('@')?;
        Some(Principal {
            subject: subject.into(),
            tenant: Some(tenant.into()),
            roles: vec![],
        })
    }
}

/// The real flow over an in-memory store, so a test can "upload" by putting bytes.
struct MemoryFiles {
    flow: FileFlow<MemoryBackend>,
}

impl FileApi for MemoryFiles {
    fn begin(&self, tenant: Option<&str>, id: &str, ct: &str, size: u64) -> Result<UploadTicket> {
        let b = self.flow.begin_upload(tenant, id, ct, size, 0)?;
        Ok(UploadTicket {
            url: b.url,
            headers: b.headers,
            expires_in_secs: b.expires_in_secs,
        })
    }
    fn finish<'a>(
        &'a self,
        tenant: Option<&'a str>,
        id: &'a str,
        ct: &'a str,
        size: u64,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.flow
                .finish_upload(tenant, id, ct, size)
                .await
                .map(|_| ())
        })
    }
    fn download(&self, tenant: Option<&str>, id: &str, name: &str) -> Result<String> {
        self.flow.download_url(tenant, id, name, 0)
    }
}

async fn app(files: Option<Arc<MemoryFiles>>) -> Router {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let (project, diags) = load_project(&[
        f(
            "app.yaml",
            "schema_version: 1\nname: filesapp\nversion: 0.1.0\ntenancy: row\ntrust_tier: standard\ndrivers: [sqlite]\n",
        ),
        f(
            "entities/doc.yaml",
            "schema_version: 1\nentity: doc\nowner: owner_id\nfields:\n  title: { type: text, required: true }\n  owner_id: { type: uuid, required: true }\n",
        ),
        f(
            "policies/doc.yaml",
            "schema_version: 1\nentity: doc\nrules:\n  - id: own\n    actions: [read]\n    allow: { owner: true }\n",
        ),
    ]);
    assert!(!falak_core::diagnostics::has_errors(&diags), "{diags:?}");
    let ir = Arc::new(build_ir(&project.unwrap()));
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    let ctx = falak_contracts::identity::RequestContext {
        principal: None,
        request_id: "t".into(),
    };
    migrate(&*driver, &ctx, &ir, MigrateOptions::default())
        .await
        .unwrap();
    create_router_with(
        ir,
        driver,
        Arc::new(TenantAuth),
        RouterOptions {
            files: files.map(|f| f as Arc<dyn FileApi>),
            ..RouterOptions::default()
        },
    )
}

fn files() -> Arc<MemoryFiles> {
    Arc::new(MemoryFiles {
        flow: FileFlow {
            config: S3Config {
                endpoint: "http://store.test".into(),
                bucket: "b".into(),
                region: "auto".into(),
                access_key: "k".into(),
                secret_key: "s".into(),
                path_style: true,
            },
            backend: MemoryBackend::default(),
            limits: UploadLimits {
                max_bytes: 1000,
                url_ttl_secs: 60,
            },
        },
    })
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

fn alice() -> String {
    format!("{ALICE}@{T1}")
}

async fn begun(app: &Router, who: &str, size: usize) -> String {
    let (s, v) = call(
        app,
        "POST",
        "/v1/_files",
        who,
        Some(json!({"name": "photo.png", "content_type": "image/png", "size": size})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["upload"]["method"], "PUT");
    assert!(v["upload"]["url"].as_str().unwrap().contains("quarantine"));
    v["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn upload_check_publish_and_download() {
    let store = files();
    let app = app(Some(store.clone())).await;
    let id = begun(&app, &alice(), PNG.len()).await;

    // Not downloadable until it has been checked.
    let (s, _) = call(&app, "GET", &format!("/v1/_files/{id}"), &alice(), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    store
        .flow
        .backend
        .put(&format!("quarantine/{T1}/{id}"), PNG);
    let (s, v) = call(
        &app,
        "POST",
        &format!("/v1/_files/{id}/complete"),
        &alice(),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["state"], "clean");

    let (s, v) = call(&app, "GET", &format!("/v1/_files/{id}"), &alice(), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let url = v["download"]["url"].as_str().unwrap();
    assert!(url.contains(&format!("files/{T1}/{id}")), "{url}");
    assert!(url.contains("attachment"));
    assert_eq!(v["name"], "photo.png");
}

#[tokio::test]
async fn a_file_that_is_not_what_it_says_is_refused_and_never_served() {
    let store = files();
    let app = app(Some(store.clone())).await;
    let exe: &[u8] = b"MZ\x90\x00 not a picture";
    let id = begun(&app, &alice(), exe.len()).await;
    store
        .flow
        .backend
        .put(&format!("quarantine/{T1}/{id}"), exe);
    let (s, v) = call(
        &app,
        "POST",
        &format!("/v1/_files/{id}/complete"),
        &alice(),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["code"], "file_content_mismatch");
    assert!(!store.flow.backend.has(&format!("quarantine/{T1}/{id}")));
    assert!(!store.flow.backend.has(&format!("files/{T1}/{id}")));
    // It cannot be completed again, and it cannot be downloaded.
    let (s, _) = call(
        &app,
        "POST",
        &format!("/v1/_files/{id}/complete"),
        &alice(),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&app, "GET", &format!("/v1/_files/{id}"), &alice(), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn nobody_else_can_complete_or_download_someone_elses_file() {
    let store = files();
    let app = app(Some(store.clone())).await;
    let id = begun(&app, &alice(), PNG.len()).await;
    store
        .flow
        .backend
        .put(&format!("quarantine/{T1}/{id}"), PNG);
    let bob_same_tenant = format!("{BOB}@{T1}");
    let bob_other_tenant = format!("{BOB}@{T2}");
    let alice_other_tenant = format!("{ALICE}@{T2}");
    for who in [&bob_same_tenant, &bob_other_tenant, &alice_other_tenant] {
        let (s, _) = call(
            &app,
            "POST",
            &format!("/v1/_files/{id}/complete"),
            who,
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{who}");
    }
    // The owner's file is still waiting, untouched.
    assert!(store.flow.backend.has(&format!("quarantine/{T1}/{id}")));
    let (s, _) = call(
        &app,
        "POST",
        &format!("/v1/_files/{id}/complete"),
        &alice(),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    for who in [&bob_same_tenant, &bob_other_tenant, &alice_other_tenant] {
        let (s, _) = call(&app, "GET", &format!("/v1/_files/{id}"), who, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{who}");
    }
}

#[tokio::test]
async fn type_and_size_are_checked_before_a_url_exists() {
    let app = app(Some(files())).await;
    for body in [
        json!({"name": "a.html", "content_type": "text/html", "size": 10}),
        json!({"name": "a.png", "content_type": "image/png", "size": 0}),
        json!({"name": "a.png", "content_type": "image/png", "size": 5000}),
        json!({"name": "", "content_type": "image/png", "size": 10}),
        json!({"content_type": "image/png", "size": 10}),
    ] {
        let (s, v) = call(&app, "POST", "/v1/_files", &alice(), Some(body.clone())).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body} -> {v}");
    }
}

#[tokio::test]
async fn without_a_token_or_a_store_the_routes_say_so() {
    let app_with = app(Some(files())).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/_files")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app_with.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    let app_without = app(None).await;
    let (s, v) = call(
        &app_without,
        "POST",
        "/v1/_files",
        &alice(),
        Some(json!({"name":"a","content_type":"image/png","size":1})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_IMPLEMENTED, "{v}");
    let _ = Error::not_found();
}
