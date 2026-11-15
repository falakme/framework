//! Studio end to end against a fake Office and a fake app, both on loopback.

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    routing::{get, patch, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use falak_studio::{AppEntry, Audit, Config, Studio, router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

fn jwt(claims: &Value) -> String {
    format!(
        "{}.{}.sig",
        B64.encode("{}"),
        B64.encode(claims.to_string())
    )
}

#[derive(Default)]
struct Seen {
    if_match: Option<String>,
    patched: Option<Value>,
    bearer: Vec<String>,
}

async fn serve(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

async fn fake_office() -> String {
    let admin = jwt(&json!({"sub": "u-admin", "roles": ["office_admin"]}));
    let plain = jwt(&json!({"sub": "u-plain", "roles": []}));
    let app = Router::new()
        .route(
            "/v1/auth/login",
            post(move |Json(b): Json<Value>| {
                let (admin, plain) = (admin.clone(), plain.clone());
                async move {
                    let token = match (b["email"].as_str(), b["password"].as_str()) {
                        (Some("admin@x.test"), Some("pw")) => admin,
                        (Some("plain@x.test"), Some("pw")) => plain,
                        _ => return (StatusCode::UNAUTHORIZED, Json(json!({"title": "no"}))),
                    };
                    (
                        StatusCode::OK,
                        Json(
                            json!({"access_token": token, "refresh_token": "r", "expires_in": 900}),
                        ),
                    )
                }
            }),
        )
        .route(
            "/v1/_office/token",
            post(|headers: HeaderMap, Json(b): Json<Value>| async move {
                assert!(headers.get("authorization").is_some());
                assert_eq!(b["audience"], "notes");
                Json(json!({"access_token": "app-token", "expires_in": 300}))
            }),
        );
    serve(app).await
}

async fn fake_app(seen: Arc<Mutex<Seen>>) -> String {
    let check = |s: &Arc<Mutex<Seen>>, h: &HeaderMap| {
        let b = h
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        s.lock().unwrap().bearer.push(b.clone());
        b == "Bearer app-token"
    };
    let schema = json!({"app": "notes", "entities": [{
    "name": "note", "path": "notes", "owner": "owner_id",
    "can": {"read": true, "create": true, "update": true, "delete": true},
    "admin": {"label": "Notes", "list_columns": ["title", "email"], "search_fields": ["title"]},
    "fields": [
        {"name": "id", "type": "uuid", "nullable": false, "pii": false, "encrypted": false, "builtin": true},
        {"name": "title", "type": "text", "nullable": false, "pii": false, "encrypted": false, "builtin": false},
        {"name": "email", "type": "text", "nullable": true, "pii": true, "encrypted": false, "builtin": false},
        {"name": "version", "type": "int64", "nullable": false, "pii": false, "encrypted": false, "builtin": true},
    ]}]});
    let row = json!({"id": "11111111-1111-1111-1111-111111111111", "title": "Hello", "email": "alice@example.com", "version": 3});
    let app = Router::new()
        .route(
            "/v1/_schema",
            get({
                let (s, schema) = (seen.clone(), schema.clone());
                move |h: HeaderMap| {
                    let (ok, schema) = (check(&s, &h), schema.clone());
                    async move {
                        if ok { (StatusCode::OK, Json(schema)) } else { (StatusCode::UNAUTHORIZED, Json(json!({}))) }
                    }
                }
            }),
        )
        .route(
            "/v1/notes",
            get({
                let row = row.clone();
                move || {
                    let row = row.clone();
                    async move { Json(json!({"data": [row], "meta": {"has_more": false}})) }
                }
            })
            .post(|Json(b): Json<Value>| async move {
                (StatusCode::CREATED, Json(json!({"id": "22222222-2222-2222-2222-222222222222", "title": b["title"], "email": b["email"], "version": 1})))
            }),
        )
        .route(
            "/v1/notes/{id}",
            get({
                let row = row.clone();
                move || {
                    let row = row.clone();
                    async move { Json(row) }
                }
            })
            .merge(patch(
                |State(s): State<Arc<Mutex<Seen>>>, h: HeaderMap, Json(b): Json<Value>| async move {
                    let mut g = s.lock().unwrap();
                    g.if_match = h.get("if-match").and_then(|v| v.to_str().ok()).map(str::to_owned);
                    g.patched = Some(b);
                    Json(json!({"id": "11111111-1111-1111-1111-111111111111", "title": "Changed", "email": "alice@example.com", "version": 4}))
                },
            )),
        )
        .with_state(seen);
    serve(app).await
}

struct Env {
    app: Router,
    seen: Arc<Mutex<Seen>>,
    audit: std::path::PathBuf,
}

async fn env() -> Env {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let office = fake_office().await;
    let app_url = fake_app(seen.clone()).await;
    let dir = std::env::temp_dir().join(format!(
        "falak-studio-test-{}-{}",
        std::process::id(),
        falak_studio::random_id().replace(['-', '_'], "x")
    ));
    let audit_path = dir.join("audit.jsonl");
    let studio = Studio::new(
        Config {
            office_url: office,
            apps: vec![AppEntry {
                name: "notes".into(),
                url: app_url,
            }],
            cookie_secure: false,
        },
        Audit::open(Some(audit_path.clone())).unwrap(),
    );
    Env {
        app: router(Arc::new(studio)),
        seen,
        audit: audit_path,
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

async fn send(
    e: &Env,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    origin: Option<&str>,
    body: Option<Value>,
) -> Reply {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "studio.test");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    if let Some(c) = csrf {
        b = b.header("x-studio-csrf", c);
    }
    if let Some(o) = origin {
        b = b.header(header::ORIGIN, o);
    }
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    let res = e
        .app
        .clone()
        .oneshot(
            b.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

/// Sign in as the administrator: the cookie to send and the CSRF token.
async fn sign_in(e: &Env) -> (String, String) {
    let r = send(
        e,
        "POST",
        "/api/login",
        None,
        None,
        None,
        Some(json!({"email": "admin@x.test", "password": "pw"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let cookie = r
        .headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    (
        cookie.split(';').next().unwrap().to_owned(),
        r.body["csrf"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn pages_carry_a_strict_policy_and_the_api_needs_a_session() {
    let e = env().await;
    let r = send(&e, "GET", "/", None, None, None, None).await;
    assert_eq!(r.status, StatusCode::OK);
    let csp = r.headers["content-security-policy"].to_str().unwrap();
    for part in [
        "default-src 'none'",
        "script-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
    ] {
        assert!(csp.contains(part), "{csp}");
    }
    assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"));
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    let r = send(&e, "GET", "/api/me", None, None, None, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.headers["cache-control"], "no-store");
    let r = send(
        &e,
        "GET",
        "/api/apps/notes/schema",
        Some("studio_session=forged"),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sign_in_sets_a_locked_cookie_and_never_shows_a_token() {
    let e = env().await;
    let r = send(
        &e,
        "POST",
        "/api/login",
        None,
        None,
        None,
        Some(json!({"email": "admin@x.test", "password": "pw"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let cookie = r.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"),
        "{cookie}"
    );
    let text = r.body.to_string();
    assert!(
        !text.contains("access") && !text.contains("refresh") && !text.contains("eyJ"),
        "{text}"
    );

    let bad = send(
        &e,
        "POST",
        "/api/login",
        None,
        None,
        None,
        Some(json!({"email": "admin@x.test", "password": "no"})),
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert!(bad.headers.get(header::SET_COOKIE).is_none());
    let plain = send(
        &e,
        "POST",
        "/api/login",
        None,
        None,
        None,
        Some(json!({"email": "plain@x.test", "password": "pw"})),
    )
    .await;
    assert_eq!(
        plain.status,
        StatusCode::UNAUTHORIZED,
        "a person with no Studio role cannot use it"
    );
    assert!(plain.headers.get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn lists_mask_personal_data_and_reveal_is_a_separate_recorded_step() {
    let e = env().await;
    let (cookie, csrf) = sign_in(&e).await;
    let r = send(
        &e,
        "GET",
        "/api/apps/notes/notes",
        Some(&cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let row = &r.body["data"][0];
    assert_eq!(row["title"], "Hello");
    assert_ne!(row["email"], "alice@example.com");
    assert!(row["email"].as_str().unwrap().contains('•'));
    assert!(!r.body.to_string().contains("alice@example.com"));

    // The page needs the CSRF token to ask for the real value.
    let id = "11111111-1111-1111-1111-111111111111";
    let uri = format!("/api/apps/notes/notes/{id}/reveal");
    let no = send(&e, "POST", &uri, Some(&cookie), None, None, Some(json!({}))).await;
    assert_eq!(no.status, StatusCode::FORBIDDEN);
    let shown = send(
        &e,
        "POST",
        &uri,
        Some(&cookie),
        Some(&csrf),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(shown.status, StatusCode::OK, "{}", shown.body);
    assert_eq!(shown.body["data"]["email"], "alice@example.com");
    let log = std::fs::read_to_string(&e.audit).unwrap();
    assert!(log.contains("\"reveal\"") && log.contains(id));
    assert!(
        !log.contains("alice@example.com"),
        "values never reach the log"
    );
}

#[tokio::test]
async fn writes_need_the_csrf_token_and_the_same_origin_and_go_through_the_app() {
    let e = env().await;
    let (cookie, csrf) = sign_in(&e).await;
    let id = "11111111-1111-1111-1111-111111111111";
    let uri = format!("/api/apps/notes/notes/{id}");
    let body = json!({"changes": {"title": "Changed"}, "version": 3});

    let r = send(
        &e,
        "PATCH",
        &uri,
        Some(&cookie),
        None,
        None,
        Some(body.clone()),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "no CSRF token");
    let r = send(
        &e,
        "PATCH",
        &uri,
        Some(&cookie),
        Some("wrong"),
        None,
        Some(body.clone()),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "wrong CSRF token");
    let r = send(
        &e,
        "PATCH",
        &uri,
        Some(&cookie),
        Some(&csrf),
        Some("http://evil.test"),
        Some(body.clone()),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "another origin");
    assert!(
        e.seen.lock().unwrap().patched.is_none(),
        "nothing reached the app"
    );

    let r = send(
        &e,
        "PATCH",
        &uri,
        Some(&cookie),
        Some(&csrf),
        Some("http://studio.test"),
        Some(body),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    {
        let seen = e.seen.lock().unwrap();
        assert_eq!(seen.if_match.as_deref(), Some("\"3\""));
        assert_eq!(seen.patched, Some(json!({"title": "Changed"})));
        assert!(
            seen.bearer.iter().all(|b| b == "Bearer app-token"),
            "the app saw an app token: {:?}",
            seen.bearer
        );
    }
    assert!(
        r.body["email"].as_str().unwrap().contains('•'),
        "the reply is masked too"
    );

    // A masked value must never be written back over the real one.
    let r = send(
        &e,
        "PATCH",
        &uri,
        Some(&cookie),
        Some(&csrf),
        None,
        Some(json!({"changes": {"email": "a••••"}, "version": 3})),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Unknown fields are not passed on.
    let r = send(
        &e,
        "PATCH",
        &uri,
        Some(&cookie),
        Some(&csrf),
        None,
        Some(json!({"changes": {"owner_id": "x"}, "version": 3})),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // A path that is not an id is refused before any call.
    let r = send(
        &e,
        "PATCH",
        "/api/apps/notes/notes/..%2Fadmin",
        Some(&cookie),
        Some(&csrf),
        None,
        Some(json!({"changes": {}, "version": 1})),
    )
    .await;
    assert!(r.status == StatusCode::BAD_REQUEST || r.status == StatusCode::NOT_FOUND);

    let log = std::fs::read_to_string(&e.audit).unwrap();
    assert!(log.contains("\"update\"") && log.contains("notes/notes/"));
    assert!(Audit::verify(&e.audit).unwrap() >= 2);
}

#[tokio::test]
async fn filters_on_personal_fields_and_unknown_apps_are_refused_and_creates_work() {
    let e = env().await;
    let (cookie, csrf) = sign_in(&e).await;
    let r = send(
        &e,
        "GET",
        "/api/apps/notes/notes?filter%5Bemail%5D=alice",
        Some(&cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::BAD_REQUEST,
        "matching would reveal the value"
    );
    let r = send(
        &e,
        "GET",
        "/api/apps/notes/notes?filter%5Btitle%5D=Hello&page%5Bsize%5D=10",
        Some(&cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(
        &e,
        "GET",
        "/api/apps/nope/notes",
        Some(&cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = send(
        &e,
        "GET",
        "/api/apps/notes/secrets",
        Some(&cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "only record types the app lists"
    );

    let r = send(
        &e,
        "POST",
        "/api/apps/notes/notes",
        Some(&cookie),
        Some(&csrf),
        None,
        Some(json!({"values": {"title": "New", "email": "b@example.com"}})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);

    // Signing out ends the session.
    let r = send(
        &e,
        "POST",
        "/api/logout",
        Some(&cookie),
        Some(&csrf),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(&e, "GET", "/api/me", Some(&cookie), None, None, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}
