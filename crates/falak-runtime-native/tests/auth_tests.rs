//! Auth middleware (T1.14): identity comes only from a verified token.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use falak_auth::{
    keys::LocalKeys,
    token::{Claims, TokenConfig, Verifier, issue},
};
use falak_contracts::{identity::RequestContext, support::Clock};
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::apply_initial_migration;
use falak_runtime_native::{context::TokenAuthenticator, create_router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const NOW: i64 = 1_800_000_000;

struct FixedClock;
impl Clock for FixedClock {
    fn now_micros(&self) -> i64 {
        NOW * 1_000_000
    }
}

fn config() -> TokenConfig {
    TokenConfig {
        issuer: "falak-local".into(),
        audience: "minimal".into(),
        leeway_secs: 0,
    }
}

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

struct Fixture {
    app: axum::Router,
    keys: LocalKeys,
}

impl Fixture {
    async fn new() -> Self {
        let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
        let (project, diags) = load_project(&files());
        assert!(diags.is_empty(), "{diags:?}");
        let ir = Arc::new(build_ir(&project.unwrap()));
        let ctx = RequestContext {
            principal: None,
            request_id: "t".into(),
        };
        apply_initial_migration(&*driver, &ctx, &ir).await.unwrap();

        let keys = LocalKeys::generate();
        let mut verifier = Verifier::new(config());
        keys.trust_all(&mut verifier);
        let app = create_router(
            ir,
            driver,
            Arc::new(TokenAuthenticator::new(verifier, FixedClock)),
        );
        Self { app, keys }
    }

    fn token_with(
        &self,
        config: &TokenConfig,
        subject: &str,
        roles: &[&str],
        expires_at: i64,
    ) -> String {
        let (kid, key) = self.keys.active();
        issue(
            key,
            kid,
            config,
            &Claims {
                subject: subject.into(),
                tenant: None,
                roles: roles.iter().map(|r| (*r).to_string()).collect(),
                issued_at: NOW - 10,
                expires_at,
                token_id: "j".into(),
            },
        )
    }

    fn token(&self, subject: &str) -> String {
        self.token_with(&config(), subject, &[], NOW + 900)
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, Value) {
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn get(&self, uri: &str, headers: &[(&str, &str)]) -> (StatusCode, Value) {
        let mut b = Request::builder().uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        self.send(b.body(Body::empty()).unwrap()).await
    }

    async fn post(&self, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
        self.send(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn a_valid_token_reaches_its_own_data() {
    let f = Fixture::new().await;
    let alice = f.token("00000000-0000-0000-0000-00000000000a");
    let (status, note) = f.post("/v1/notes", &alice, json!({"title": "mine"})).await;
    assert_eq!(status, StatusCode::CREATED, "{note}");
    assert_eq!(note["owner_id"], "00000000-0000-0000-0000-00000000000a");

    let (status, page) = f
        .get("/v1/notes", &[("authorization", &bearer(&alice))])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["data"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_user_id_in_a_header_without_a_token_is_rejected() {
    let f = Fixture::new().await;
    for headers in [
        vec![("x-user-id", "00000000-0000-0000-0000-00000000000a")],
        vec![("x-falak-subject", "00000000-0000-0000-0000-00000000000a")],
        vec![("x-forwarded-user", "admin"), ("x-user-roles", "admin")],
    ] {
        let (status, body) = f.get("/v1/notes", &headers).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{headers:?}");
        assert_eq!(body["code"], "unauthenticated");
    }
    // And a user id in the query string.
    let (status, _) = f.get("/v1/notes?user_id=x&subject=x", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_user_id_header_does_not_override_a_valid_token() {
    let f = Fixture::new().await;
    let alice = f.token("00000000-0000-0000-0000-00000000000a");
    let bob = f.token("00000000-0000-0000-0000-00000000000b");
    f.post("/v1/notes", &alice, json!({"title": "alice's"}))
        .await;
    let (status, page) = f
        .get(
            "/v1/notes",
            &[
                ("authorization", &bearer(&bob)),
                ("x-user-id", "00000000-0000-0000-0000-00000000000a"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(page["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn bad_credentials_are_all_401() {
    let f = Fixture::new().await;
    let good = f.token("u");
    let (head, tail) = good.rsplit_once('.').unwrap();
    let flipped = format!("{head}.{}", tail.replacen(&tail[..2], "AA", 1));

    let mut wrong_audience = config();
    wrong_audience.audience = "another-app".into();
    let mut wrong_issuer = config();
    wrong_issuer.issuer = "someone-else".into();

    let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
        ("no header", vec![]),
        ("empty bearer", vec![("authorization", "Bearer ".into())]),
        (
            "not a bearer scheme",
            vec![("authorization", format!("Basic {good}"))],
        ),
        (
            "a bare uuid",
            vec![(
                "authorization",
                bearer("00000000-0000-0000-0000-00000000000a"),
            )],
        ),
        (
            "a forged dev token",
            vec![(
                "authorization",
                bearer("sub:00000000-0000-0000-0000-00000000000a,role:admin"),
            )],
        ),
        (
            "a damaged signature",
            vec![("authorization", bearer(&flipped))],
        ),
        (
            "an expired token",
            vec![(
                "authorization",
                bearer(&f.token_with(&config(), "u", &[], NOW - 1)),
            )],
        ),
        (
            "a token for another app",
            vec![(
                "authorization",
                bearer(&f.token_with(&wrong_audience, "u", &[], NOW + 900)),
            )],
        ),
        (
            "a token from another issuer",
            vec![(
                "authorization",
                bearer(&f.token_with(&wrong_issuer, "u", &[], NOW + 900)),
            )],
        ),
        (
            "a token signed by another key",
            vec![("authorization", {
                let other = Fixture::new().await;
                bearer(&other.token("u"))
            })],
        ),
        (
            "two authorization headers",
            vec![
                ("authorization", bearer(&good)),
                ("authorization", bearer(&good)),
            ],
        ),
        (
            "a token with spaces",
            vec![("authorization", format!("Bearer {good} extra"))],
        ),
    ];
    for (name, headers) in cases {
        let pairs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let (status, body) = f.get("/v1/notes", &pairs).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(body["code"], "unauthenticated", "{name}");
        // The answer never says why.
        assert_eq!(body["detail"], "Authentication is required.", "{name}");
    }
}

#[tokio::test]
async fn the_scheme_name_is_case_insensitive() {
    let f = Fixture::new().await;
    let t = f.token("u");
    let (status, _) = f
        .get("/v1/notes", &[("authorization", &format!("bearer {t}"))])
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_token_cannot_reach_another_users_row() {
    let f = Fixture::new().await;
    let alice = f.token("00000000-0000-0000-0000-00000000000a");
    let bob = f.token("00000000-0000-0000-0000-00000000000b");
    let (_, note) = f
        .post("/v1/notes", &alice, json!({"title": "private"}))
        .await;
    let uri = format!("/v1/notes/{}", note["id"].as_str().unwrap());

    let (status, _) = f.get(&uri, &[("authorization", &bearer(&bob))]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = f.get(&uri, &[("authorization", &bearer(&alice))]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn roles_come_from_the_signed_claims_only() {
    let f = Fixture::new().await;
    let alice = f.token("00000000-0000-0000-0000-00000000000a");
    f.post("/v1/notes", &alice, json!({"title": "alice's"}))
        .await;

    // The minimal policy lets `admin` read everything.
    let plain = f.token("00000000-0000-0000-0000-00000000000c");
    let admin = f.token_with(
        &config(),
        "00000000-0000-0000-0000-00000000000c",
        &["admin"],
        NOW + 900,
    );
    let (_, page) = f
        .get("/v1/notes", &[("authorization", &bearer(&plain))])
        .await;
    assert!(page["data"].as_array().unwrap().is_empty());
    // A role named in a header does nothing.
    let (_, page) = f
        .get(
            "/v1/notes",
            &[("authorization", &bearer(&plain)), ("x-roles", "admin")],
        )
        .await;
    assert!(page["data"].as_array().unwrap().is_empty());
    let (_, page) = f
        .get("/v1/notes", &[("authorization", &bearer(&admin))])
        .await;
    assert_eq!(page["data"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn health_endpoints_need_no_token() {
    let f = Fixture::new().await;
    let res = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

async fn patch(f: &Fixture, id: &str, token: &str, if_match: &str, body: Value) -> StatusCode {
    f.send(
        Request::builder()
            .method("PATCH")
            .uri(format!("/v1/notes/{id}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::IF_MATCH, if_match)
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .0
}

#[tokio::test]
async fn if_match_on_a_row_you_cannot_see_is_404_not_412() {
    let f = Fixture::new().await;
    let alice = f.token("00000000-0000-0000-0000-00000000000a");
    let bob = f.token("00000000-0000-0000-0000-00000000000b");
    let (_, note) = f
        .post("/v1/notes", &alice, json!({"title": "private"}))
        .await;
    let id = note["id"].as_str().unwrap();

    // Bob learns nothing: a row he cannot see looks exactly like a row that is not there.
    let theirs = patch(&f, id, &bob, "W/\"1\"", json!({"title": "x"})).await;
    let missing = patch(
        &f,
        "00000000-0000-4000-8000-000000000999",
        &bob,
        "W/\"1\"",
        json!({"title": "x"}),
    )
    .await;
    assert_eq!(theirs, StatusCode::NOT_FOUND);
    assert_eq!(missing, StatusCode::NOT_FOUND);

    // The owner still gets a real version conflict, and a real success.
    assert_eq!(
        patch(&f, id, &alice, "W/\"7\"", json!({"title": "x"})).await,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        patch(&f, id, &alice, "W/\"1\"", json!({"title": "x"})).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_reused_idempotency_key_with_another_body_is_422() {
    let f = Fixture::new().await;
    let alice = f.token("00000000-0000-0000-0000-00000000000a");
    let send = |title: &'static str| {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/notes")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {alice}"))
            .header("idempotency-key", "k-1")
            .body(Body::from(json!({"title": title}).to_string()))
            .unwrap();
        f.send(req)
    };
    assert_eq!(send("one").await.0, StatusCode::CREATED);
    assert_eq!(
        send("one").await.0,
        StatusCode::CREATED,
        "same body replays"
    );
    let (status, body) = send("two").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "idempotency_payload_mismatch");
}
