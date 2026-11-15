//! The /v1/auth routes, wired to the token check on the data routes.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use falak_auth::{
    identity::{LocalIdentity, Policy},
    keys::LocalKeys,
    store::MemoryStore,
    system::{RandomIds, SystemClock},
    token::{TokenConfig, Verifier},
};
use falak_contracts::identity::RequestContext;
use falak_core::{
    build::build_ir,
    load::{SourceFile, load_project},
};
use falak_driver_sqlite::SqliteDriver;
use falak_migrate::apply_initial_migration;
use falak_runtime_native::{
    auth_routes::{AUTH_RATE, auth_router},
    context::TokenAuthenticator,
    create_router,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const PW: &str = "correct horse battery";

struct App {
    router: Router,
    resets: Arc<Mutex<Vec<(String, String)>>>,
}

fn config() -> TokenConfig {
    TokenConfig {
        issuer: "falak-local".into(),
        audience: "minimal".into(),
        leeway_secs: 0,
    }
}

async fn app() -> App {
    let f = |p: &str, t: &str| SourceFile {
        path: p.into(),
        text: t.into(),
    };
    let (project, diags) = load_project(&[
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
    ]);
    assert!(diags.is_empty(), "{diags:?}");
    let ir = Arc::new(build_ir(&project.unwrap()));
    let driver = Arc::new(SqliteDriver::in_memory().await.unwrap());
    let ctx = RequestContext {
        principal: None,
        request_id: "t".into(),
    };
    apply_initial_migration(&*driver, &ctx, &ir).await.unwrap();

    let keys = LocalKeys::generate();
    let mut verifier = Verifier::new(config());
    keys.trust_all(&mut verifier);
    let identity = LocalIdentity::new(
        MemoryStore::new(),
        keys,
        config(),
        Policy::default(),
        SystemClock,
        RandomIds,
    );
    let resets = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let resets = resets.clone();
        Arc::new(move |email: &str, token: &str| {
            resets
                .lock()
                .unwrap()
                .push((email.to_owned(), token.to_owned()));
        })
    };
    let router = create_router(
        ir,
        driver,
        Arc::new(TokenAuthenticator::new(verifier, SystemClock)),
    )
    .merge(auth_router(Arc::new(identity), sink));
    App { router, resets }
}

impl App {
    async fn call(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value, axum::http::HeaderMap) {
        let mut b = Request::builder().method(method).uri(uri);
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        if let Some(t) = token {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let req = b
            .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
            .unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            headers,
        )
    }

    async fn post(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        let (s, v, _) = self.call("POST", uri, None, Some(body)).await;
        (s, v)
    }

    async fn sign_up_and_in(&self, email: &str) -> Value {
        let (s, _) = self
            .post("/v1/auth/signup", json!({"email": email, "password": PW}))
            .await;
        assert_eq!(s, StatusCode::CREATED);
        let (s, tokens) = self
            .post("/v1/auth/login", json!({"email": email, "password": PW}))
            .await;
        assert_eq!(s, StatusCode::OK);
        tokens
    }
}

#[tokio::test]
async fn sign_up_log_in_and_use_the_token() {
    let app = app().await;
    let (status, body) = app
        .post(
            "/v1/auth/signup",
            json!({"email": "Ann@Example.com", "password": PW}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["id"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 36);

    let (status, tokens) = app
        .post(
            "/v1/auth/login",
            json!({"email": "ann@example.com", "password": PW}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 900);
    let access = tokens["access_token"].as_str().unwrap();

    // The token works on the data routes and the subject is the user id.
    let (status, note, _) = app
        .call(
            "POST",
            "/v1/notes",
            Some(access),
            Some(json!({"title": "hello"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{note}");
    assert_eq!(note["owner_id"], id);
}

#[tokio::test]
async fn responses_are_not_cached_and_errors_are_problem_documents() {
    let app = app().await;
    let (status, _, headers) = app
        .call(
            "POST",
            "/v1/auth/login",
            None,
            Some(json!({"email": "a@example.com", "password": PW})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/problem+json")
    );

    app.post(
        "/v1/auth/signup",
        json!({"email": "a@example.com", "password": PW}),
    )
    .await;
    let (_, _, headers) = app
        .call(
            "POST",
            "/v1/auth/login",
            None,
            Some(json!({"email": "a@example.com", "password": PW})),
        )
        .await;
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn unknown_email_and_wrong_password_look_the_same() {
    let app = app().await;
    app.post(
        "/v1/auth/signup",
        json!({"email": "a@example.com", "password": PW}),
    )
    .await;
    let (s1, b1) = app
        .post(
            "/v1/auth/login",
            json!({"email": "a@example.com", "password": "wrong wrong wrong"}),
        )
        .await;
    let (s2, b2) = app
        .post(
            "/v1/auth/login",
            json!({"email": "ghost@example.com", "password": PW}),
        )
        .await;
    assert_eq!(
        (s1, s2),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED)
    );
    assert_eq!(b1["code"], b2["code"]);
    assert_eq!(b1["detail"], b2["detail"]);
    assert_eq!(b1["code"], "invalid_credentials");
}

#[tokio::test]
async fn bad_bodies_are_400_with_the_field_named() {
    let app = app().await;
    for (uri, body) in [
        ("/v1/auth/signup", json!({"email": "a@example.com"})),
        ("/v1/auth/signup", json!({"password": PW})),
        ("/v1/auth/signup", json!({"email": 5, "password": PW})),
        ("/v1/auth/login", json!({})),
        ("/v1/auth/refresh", json!({})),
        ("/v1/auth/logout", json!({"refresh_token": null})),
        ("/v1/auth/password-reset", json!({})),
        ("/v1/auth/password-reset/confirm", json!({"token": "x"})),
    ] {
        let (status, doc) = app.post(uri, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(doc["code"], "invalid_body");
        assert!(doc["invalid_params"][0]["name"].is_string());
    }
    // Not JSON, not an object, empty.
    for raw in ["nope", "[1]", "\"x\"", ""] {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/auth/login")
            .body(Body::from(raw))
            .unwrap();
        let res = app.router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{raw:?}");
    }
    // Too large.
    let big = "x".repeat(20_000);
    let (status, _) = app
        .post("/v1/auth/login", json!({"email": big, "password": PW}))
        .await;
    assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn weak_password_and_duplicate_email() {
    let app = app().await;
    let (status, body) = app
        .post(
            "/v1/auth/signup",
            json!({"email": "a@example.com", "password": "short"}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "weak_password");
    app.post(
        "/v1/auth/signup",
        json!({"email": "a@example.com", "password": PW}),
    )
    .await;
    let (status, body) = app
        .post(
            "/v1/auth/signup",
            json!({"email": "A@example.com", "password": PW}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "email_taken");
}

#[tokio::test]
async fn refresh_rotates_and_logout_ends_the_session() {
    let app = app().await;
    let tokens = app.sign_up_and_in("a@example.com").await;
    let refresh = tokens["refresh_token"].as_str().unwrap();

    let (status, next) = app
        .post("/v1/auth/refresh", json!({"refresh_token": refresh}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app
        .post("/v1/auth/refresh", json!({"refresh_token": refresh}))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the old token is dead");
    // Reuse ended the new session too.
    let (status, _) = app
        .post(
            "/v1/auth/refresh",
            json!({"refresh_token": next["refresh_token"]}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let tokens = app.sign_up_and_in("b@example.com").await;
    let (status, _, _) = app
        .call(
            "POST",
            "/v1/auth/logout",
            None,
            Some(json!({"refresh_token": tokens["refresh_token"]})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = app
        .post(
            "/v1/auth/refresh",
            json!({"refresh_token": tokens["refresh_token"]}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn password_reset_is_single_use_and_answers_the_same_for_unknown_emails() {
    let app = app().await;
    app.sign_up_and_in("a@example.com").await;

    let (s1, b1) = app
        .post("/v1/auth/password-reset", json!({"email": "a@example.com"}))
        .await;
    let (s2, b2) = app
        .post(
            "/v1/auth/password-reset",
            json!({"email": "ghost@example.com"}),
        )
        .await;
    assert_eq!((s1, s2), (StatusCode::ACCEPTED, StatusCode::ACCEPTED));
    assert_eq!(b1, b2);
    let sent = app.resets.lock().unwrap().clone();
    assert_eq!(
        sent.len(),
        1,
        "a token is delivered only for a real account"
    );
    assert_eq!(sent[0].0, "a@example.com");

    let new_pw = "a brand new passphrase";
    let (status, _, _) = app
        .call(
            "POST",
            "/v1/auth/password-reset/confirm",
            None,
            Some(json!({"token": sent[0].1, "new_password": new_pw})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = app
        .post(
            "/v1/auth/password-reset/confirm",
            json!({"token": sent[0].1, "new_password": "yet another passphrase"}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_reset_token");

    let (status, _) = app
        .post(
            "/v1/auth/login",
            json!({"email": "a@example.com", "password": PW}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = app
        .post(
            "/v1/auth/login",
            json!({"email": "a@example.com", "password": new_pw}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn too_many_requests_from_one_address_get_429_with_retry_after() {
    let app = app().await;
    let mut last = StatusCode::OK;
    let mut headers = axum::http::HeaderMap::new();
    for _ in 0..=AUTH_RATE.limit {
        let (s, _, h) = app
            .call(
                "POST",
                "/v1/auth/login",
                None,
                Some(json!({"email": "x@example.com", "password": PW})),
            )
            .await;
        last = s;
        headers = h;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.contains_key("retry-after"));
    assert_eq!(headers["ratelimit-remaining"], "0");
}

#[tokio::test]
async fn the_auth_routes_ignore_a_bearer_token() {
    let app = app().await;
    // A bad token must not stop someone logging in.
    let (status, _, _) = app
        .call(
            "POST",
            "/v1/auth/signup",
            Some("garbage"),
            Some(json!({"email": "z@example.com", "password": PW})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn the_public_key_set_is_published_and_has_no_secrets() {
    let app = app().await;
    let (status, body, headers) = app.call("GET", "/.well-known/jwks.json", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "OKP");
    assert_eq!(keys[0]["crv"], "Ed25519");
    assert!(keys[0].get("d").is_none(), "a private key part leaked");
}
